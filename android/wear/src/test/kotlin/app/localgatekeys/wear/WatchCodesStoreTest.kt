package app.localgatekeys.wear

import app.localgatekeys.core.wear.WearCodes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class WatchCodesStoreTest {
    private class MemPrefs : WatchPrefs {
        val strings = mutableMapOf<String, String>()
        val longs = mutableMapOf<String, Long>()
        override fun getString(key: String) = strings[key]
        override fun getLong(key: String) = longs[key]
        override fun edit(strings: Map<String, String?>, longs: Map<String, Long?>) {
            strings.forEach { (k, v) -> if (v == null) this.strings.remove(k) else this.strings[k] = v }
            longs.forEach { (k, v) -> if (v == null) this.longs.remove(k) else this.longs[k] = v }
        }
    }

    private class Clock(var wall: Long, var elapsed: Long) : WatchClock {
        override fun wallMillis() = wall
        override fun elapsedMillis() = elapsed
        fun advance(ms: Long) { wall += ms; elapsed += ms }
    }

    private val t0 = 1_790_000_000_000L
    private val prefs = MemPrefs()
    private val clock = Clock(t0, 50_000)
    private val store = WatchCodesStore(prefs, clock)

    private fun replace(seq: Long, vararg codes: Pair<String, String>, ms: Long = 20_000, sentAt: Long = clock.wall) =
        WearCodes.Replace(seq, codes.map { WearCodes.Code(it.first, it.second, ms) }, sentAt)

    private fun known() = store.input() as TileInput.Known

    @Before fun freshProcess() = WatchCodesStore.dropMemory()

    @Test fun nothing_yet_is_no_data() {
        assertEquals(TileInput.NoData, store.input())
    }

    @Test fun codes_show_until_their_validity_ends_then_only_titles() {
        assertTrue(store.apply(replace(10, "GitHub" to "123456", "Bank" to "")))
        assertEquals(listOf("123456", ""), known().codes.map { it.code })
        clock.advance(18_900) // 20 s minus the 1 s margin: still valid
        assertEquals("123456", known().codes[0].code)
        clock.advance(200)
        val k = known()
        assertNull(k.codes[0].code)
        assertEquals("", k.codes[1].code)
        assertEquals(listOf("GitHub", "Bank"), k.codes.map { it.title })
        assertEquals(19L, k.ageSeconds)
    }

    @Test fun codes_never_reach_the_disk_and_a_new_process_has_none() {
        store.apply(replace(10, "GitHub" to "123456"))
        assertTrue(prefs.strings.values.none { "123456" in it })
        WatchCodesStore.dropMemory()
        assertNull(known().codes.single().code)
        assertEquals("GitHub", known().codes.single().title)
    }

    @Test fun a_clock_going_back_hides_the_digits() {
        store.apply(replace(10, "GitHub" to "123456"))
        clock.wall -= 5_000
        assertNull(known().codes.single().code)
    }

    @Test fun a_late_send_time_shortens_the_validity() {
        // Sent 4 s before it arrived: 20 s from the send, minus the margin.
        store.apply(replace(10, "GitHub" to "123456", sentAt = t0 - 4_000))
        clock.advance(14_900)
        assertEquals("123456", known().codes.single().code)
        clock.advance(200)
        assertNull(known().codes.single().code)
    }

    @Test fun forget_is_always_applied_and_clears_titles() {
        store.apply(replace(t0, "GitHub" to "123456"))
        assertTrue(store.apply(WearCodes.Forget(5)))
        assertEquals(TileInput.Locked(immediately = false), store.input())
        // A replace above the forget's order is accepted again; one below it is not.
        assertFalse(store.apply(replace(4, "Old" to "111111")))
        assertTrue(store.apply(replace(6, "GitHub" to "654321")))
        assertEquals("654321", known().codes.single().code)
        store.apply(WearCodes.Forget(7, immediately = true))
        assertEquals(TileInput.Locked(immediately = true), store.input())
    }

    @Test fun a_stale_replace_is_ignored() {
        store.apply(replace(20, "New" to "123456"))
        assertFalse(store.apply(replace(19, "Old" to "999999")))
        assertFalse(store.apply(replace(20, "Same" to "999999")))
        assertEquals("New", known().codes.single().title)
        assertEquals("123456", known().codes.single().code)
    }

    @Test fun an_implausible_stored_order_is_repaired() {
        prefs.longs["seq"] = Long.MAX_VALUE
        assertTrue(store.apply(replace(7, "GitHub" to "123456")))
        assertEquals(7L, prefs.longs["seq"])
    }
}
