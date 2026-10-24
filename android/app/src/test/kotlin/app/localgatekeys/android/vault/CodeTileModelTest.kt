package app.localgatekeys.android.vault

import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.totp.Totp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class CodeTileModelTest {
    private val secret = "JBSWY3DPEHPK3PXP"
    private fun login(secretText: String = secret, extra: Array<Pair<String, app.localgatekeys.core.json.JsonValue>> = emptyArray()) =
        item("web", "title" to s("Example"), "totp" to rec("secret" to s(secretText), *extra))

    @Test fun the_code_and_the_countdown_come_from_the_clock() {
        val clock = TestClock(1_000_000_010)
        val t = CodeTileModel(login(), clock).state!!
        assertEquals(Totp.code(secret, "SHA1", 6, 30, 1_000_000_010), t.code)
        assertEquals(30, t.period)
        assertEquals(30 - (1_000_000_010L % 30).toInt(), t.secondsRemaining)
        assertEquals(t.secondsRemaining / 30.0, t.fractionRemaining, 1e-12)
    }

    @Test fun tick_moves_to_the_next_code_at_the_period_boundary() {
        val clock = TestClock(30 * 1000L + 29)
        val m = CodeTileModel(login(), clock)
        val before = m.state!!
        assertEquals(1, before.secondsRemaining)
        clock.now += 1
        val after = m.state!!
        assertEquals(30, after.secondsRemaining)
        assertEquals(Totp.code(secret, "SHA1", 6, 30, clock.now), after.code)
    }

    @Test fun optional_algorithm_digits_and_period_are_used() {
        val clock = TestClock(1_700_000_000)
        val m = CodeTileModel(
            login(extra = arrayOf("algorithm" to s("SHA256"), "digits" to i(8), "period" to i(60))),
            clock,
        )
        val st = m.state!!
        assertEquals(Totp.code(secret, "SHA256", 8, 60, clock.now), st.code)
        assertEquals(8, st.code.length)
        assertEquals(60, st.period)
    }

    @Test fun a_secret_that_does_not_decode_shows_no_code() {
        val clock = TestClock(1_700_000_000)
        assertNull(CodeTileModel(login("not base32 !!"), clock).state)
        assertNull(CodeTileModel(login(extra = arrayOf("digits" to i(3))), clock).state)
        assertNull(CodeTileModel(item("web", "totp" to rec("secret" to i(5))), clock).state)
    }

    @Test fun the_code_is_grouped_three_and_three_and_the_last_seven_seconds_are_urgent() {
        assertEquals("123 456", CodeTileModel.grouped("123456"))
        assertEquals("12345678", CodeTileModel.grouped("12345678"))
        assertEquals("", CodeTileModel.grouped(""))
        assertTrue(CodeTileModel.isUrgent(7))
        assertTrue(CodeTileModel.isUrgent(1))
        assertFalse(CodeTileModel.isUrgent(8))
    }

    @Test fun copy_hands_the_plain_code_to_the_sink_and_reports_whether_there_was_one() {
        val clock = TestClock(1_700_000_000)
        val copied = mutableListOf<String>()
        val m = CodeTileModel(login(), clock)
        assertTrue(m.copy { copied.add(it) })
        assertEquals(listOf(Totp.code(secret, "SHA1", 6, 30, clock.now)), copied)
        assertFalse(CodeTileModel(login("zzz!"), clock).copy { copied.add(it) })
        assertEquals(1, copied.size)
    }

    @Test fun an_edited_item_gets_a_new_model_so_the_old_code_never_shows() {
        val clock = TestClock(1_700_000_000)
        val first = login()
        val m = CodeTileModel.modelFor(first, null, clock)
        assertSame(m, CodeTileModel.modelFor(first.copy(), m, clock)) // an equal item keeps its model
        val edited = login("GEZDGNBVGY3TQOJQ")
        val fresh = CodeTileModel.modelFor(edited, m, clock)
        assertNotSame(m, fresh)
        val old = m.state!!.code
        assertNotNull(fresh.state)
        assertEquals(Totp.code("GEZDGNBVGY3TQOJQ", "SHA1", 6, 30, clock.now), fresh.state!!.code)
        assertFalse(old == fresh.state!!.code)
        val copied = mutableListOf<String>()
        fresh.copy { copied.add(it) }
        assertEquals(listOf(fresh.state!!.code), copied)
    }
}
