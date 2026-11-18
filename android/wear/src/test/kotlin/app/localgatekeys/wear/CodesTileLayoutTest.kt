package app.localgatekeys.wear

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CodesTileLayoutTest {
    /** The English strings, read from the module's own res/values/strings.xml. */
    private val texts = object : TileTexts {
        private val strings: Map<String, String> =
            Regex("<string name=\"([a-z_]+)\"[^>]*>([^<]*)</string>").findAll(File("src/main/res/values/strings.xml").readText())
                .associate { it.groupValues[1] to it.groupValues[2].replace("\'", "'") }

        private fun s(key: String, n: Long? = null) = strings.getValue(key).let { if (n == null) it else it.replace("%1\$d", n.toString()) }
        override fun noData() = s("tile_no_data")
        override fun locked() = s("tile_locked")
        override fun lockedImmediately() = s("tile_locked_immediately")
        override fun empty() = s("tile_empty")
        override fun watchLocked() = s("tile_watch_locked")
        override fun updatedNow() = s("tile_updated_now")
        override fun updatedMinutes(n: Long) = s("tile_updated_minutes", n)
        override fun updatedHours(n: Long) = s("tile_updated_hours", n)
        override fun updatedDays(n: Long) = s("tile_updated_days", n)
    }

    private fun footer(m: TileModel) = CodesTileLayout.footerText(m.footer, texts)

    @Test fun two_codes_give_two_rows() {
        val m = CodesTileLayout.model(listOf(PinnedCode("GitHub", "123456", 20_000), PinnedCode("Bank", "12345678", 20_000)), ageSeconds = 3)
        assertEquals(2, m.rows.size)
        assertEquals(listOf("123 456", "1234 5678"), m.rows.map { it.digits })
        assertEquals(listOf("GitHub", "Bank"), m.rows.map { it.title })
        assertEquals("Updated just now", footer(m))
        // The protolayout tree builds (Column of rows and spacers plus the footer).
        CodesTileLayout.layout(m, texts)
    }

    @Test fun an_old_state_shows_its_age() {
        val m = CodesTileLayout.model(listOf(PinnedCode("GitHub", null)), ageSeconds = 150)
        assertEquals("Updated 2 min ago", footer(m))
        assertEquals("Updated 3 h ago", footer(CodesTileLayout.model(listOf(PinnedCode("a", null)), ageSeconds = 3 * 3_600 + 5)))
        assertEquals("Updated 4 d ago", footer(CodesTileLayout.model(listOf(PinnedCode("a", null)), ageSeconds = 4 * 86_400)))
        // The titles stay, the expired digits do not.
        assertEquals(CodesTileLayout.HIDDEN, m.rows.single().digits)
        assertFalse(m.rows.single().shown)
    }

    @Test fun no_data_asks_to_open_the_phone_app() {
        val m = CodesTileLayout.model(null, ageSeconds = 0)
        assertTrue(m.rows.isEmpty())
        assertEquals("Open LocalGateKeys on your phone", footer(m))
        CodesTileLayout.layout(m, texts)
    }

    @Test fun locked_phone_shows_no_titles() {
        val m = CodesTileLayout.model(TileInput.Locked(immediately = false))
        assertTrue(m.rows.isEmpty())
        assertEquals("Unlock LocalGateKeys on your phone to see codes", footer(m))
        assertTrue(footer(CodesTileLayout.model(TileInput.Locked(immediately = true))).startsWith("Set Auto-lock"))
        assertEquals("Pin a code in LocalGateKeys", footer(CodesTileLayout.model(emptyList(), 0)))
    }

    @Test fun a_locked_watch_hides_the_digits() {
        val m = CodesTileLayout.model(listOf(PinnedCode("GitHub", "123456", 20_000), PinnedCode("Odd", "")), 0, watchLocked = true)
        assertTrue(m.rows.none { it.shown || "123" in it.digits })
        assertEquals("Unlock your watch to see codes", footer(m))
        // No code at all: a dash, not hidden dots.
        assertEquals(CodesTileLayout.NO_CODE, CodesTileLayout.model(listOf(PinnedCode("Odd", "")), 0).rows.single().digits)
    }

    @Test fun to_string_never_shows_a_code() {
        assertFalse("123456" in PinnedCode("GitHub", "123456").toString())
        assertFalse("123" in CodesTileLayout.model(listOf(PinnedCode("GitHub", "123456", 1)), 0).toString())
    }
}
