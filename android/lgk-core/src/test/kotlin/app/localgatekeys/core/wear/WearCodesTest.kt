package app.localgatekeys.core.wear

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WearCodesTest {
    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

    @Test
    fun replace_round_trips_and_carries_no_secret_field() {
        val m = WearCodes.Replace(7, listOf(WearCodes.Code("GitHub", "123456", 12_000), WearCodes.Code("Bank", "", 0)), 1_700_000_000_000)
        val bytes = WearCodes.encode(m)
        assertEquals(
            "{\"at\":1700000000000,\"codes\":[{\"c\":\"123456\",\"ms\":12000,\"t\":\"GitHub\"},{\"c\":\"\",\"ms\":0,\"t\":\"Bank\"}],\"kind\":\"codes\",\"seq\":7,\"v\":1}",
            bytes.toString(Charsets.UTF_8),
        )
        assertEquals(m, WearCodes.decode(bytes))
    }

    @Test
    fun forget_round_trips_with_reason() {
        assertEquals(WearCodes.Forget(3), WearCodes.decode(WearCodes.encode(WearCodes.Forget(3))))
        assertEquals(WearCodes.Forget(4, true), WearCodes.decode(WearCodes.encode(WearCodes.Forget(4, true))))
    }

    @Test
    fun encode_cleans_what_it_sends() {
        val long = "x".repeat(60)
        val m = WearCodes.Replace(1, List(6) { WearCodes.Code("a\u0007$long", "12ab56", 999_999) })
        val back = WearCodes.decode(WearCodes.encode(m)) as WearCodes.Replace
        assertEquals(WearCodes.MAX_CODES, back.codes.size)
        assertEquals(WearCodes.MAX_TITLE, back.codes[0].title.length)
        assertEquals("", back.codes[0].code) // not digits: never sent
        assertEquals(WearCodes.MAX_VALID_MILLIS, back.codes[0].millisRemaining)
    }

    @Test
    fun decode_rejects_malformed_input() {
        val bad = listOf(
            "", "[]", "{}", "not json",
            "{\"v\":2,\"seq\":1,\"kind\":\"forget\"}",
            "{\"v\":1,\"seq\":-1,\"kind\":\"forget\"}",
            "{\"v\":1,\"seq\":1,\"kind\":\"other\"}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\"}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"codes\":[]}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":-1,\"codes\":[]}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":1,\"codes\":[{\"t\":\"a\",\"c\":\"12x456\",\"ms\":1}]}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":1,\"codes\":[{\"t\":\"a\",\"c\":\"123456\",\"ms\":300001}]}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":1,\"codes\":[{\"t\":\"a\\u0000\",\"c\":\"123456\",\"ms\":1}]}",
            "{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":1,\"codes\":[{\"c\":\"123456\",\"ms\":1}]}",
            "{\"v\":1,\"v\":1,\"seq\":1,\"kind\":\"forget\"}",
        )
        for (s in bad) assertNull(WearCodes.decode(utf8(s)), s)
        val five = (1..5).joinToString(",") { "{\"t\":\"a\",\"c\":\"123456\",\"ms\":1}" }
        assertNull(WearCodes.decode(utf8("{\"v\":1,\"seq\":1,\"kind\":\"codes\",\"at\":1,\"codes\":[$five]}")))
        assertNull(WearCodes.decode(ByteArray(WearCodes.MAX_BYTES + 1) { ' '.code.toByte() }))
    }

    @Test
    fun next_sequence_rises_and_saturates() {
        assertEquals(1_000L, WearCodes.nextSequence(5, 1_000))
        assertEquals(1_001L, WearCodes.nextSequence(1_000, 900)) // clock went back
        assertEquals(Long.MAX_VALUE, WearCodes.nextSequence(Long.MAX_VALUE, 0))
        assertEquals(1L, WearCodes.nextSequence(0, -5))
    }

    @Test
    fun forget_is_always_applied_and_resets_the_order() {
        val now = 1_700_000_000_000L
        assertEquals(true to 10L, WearCodes.ordering(WearCodes.Replace(10, emptyList()), null, now))
        assertEquals(false to 10L, WearCodes.ordering(WearCodes.Replace(9, emptyList()), 10, now))
        assertEquals(false to 10L, WearCodes.ordering(WearCodes.Replace(10, emptyList()), 10, now))
        // A forget with a lower order clears and becomes the last order; a later replace above it is accepted.
        assertEquals(true to 5L, WearCodes.ordering(WearCodes.Forget(5), now, now))
        assertEquals(true to 6L, WearCodes.ordering(WearCodes.Replace(6, emptyList()), 5, now))
        assertEquals(false to 5L, WearCodes.ordering(WearCodes.Replace(4, emptyList()), 5, now))
    }

    @Test
    fun implausible_stored_order_is_dropped() {
        val now = 1_700_000_000_000L
        assertFalse(WearCodes.plausible(-1, now))
        assertFalse(WearCodes.plausible(Long.MAX_VALUE, now))
        assertFalse(WearCodes.plausible(now + 2 * 86_400_000L, now))
        assertTrue(WearCodes.plausible(now + 1_000, now))
        assertEquals(true to 7L, WearCodes.ordering(WearCodes.Replace(7, emptyList()), Long.MAX_VALUE, now))
    }

    @Test
    fun to_string_never_shows_a_code() {
        val s = WearCodes.Replace(1, listOf(WearCodes.Code("GitHub", "987654", 1))).toString()
        assertFalse("987654" in s)
        assertFalse("GitHub" in WearCodes.Code("GitHub", "987654", 1).toString())
    }
}
