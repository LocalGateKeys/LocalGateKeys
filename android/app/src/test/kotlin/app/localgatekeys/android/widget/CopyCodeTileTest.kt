package app.localgatekeys.android.widget

import app.localgatekeys.android.R
import app.localgatekeys.android.codes.PinnedCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class CopyCodeTileTest {
    private fun code(id: String, code: String?, left: Int = 10) =
        PinnedCode(id, if (code == null) "" else "Site $id", code, left)

    @Test fun nothing_pinned_is_inactive_and_says_so() {
        val s = TileState.from(emptyList())
        assertSame(TileState.Empty, s)
        assertFalse(s.active)
        assertEquals(R.string.tile_codes_empty, TileState.labelRes(s))
        assertSame(TileState.Empty, TileState.from(emptyList(), deviceLocked = true))
    }

    @Test fun one_unlocked_code_is_active_with_its_title() {
        val s = TileState.from(listOf(code("a", "123456")))
        assertTrue(s is TileState.Ready)
        assertTrue(s.active)
        assertEquals("a", (s as TileState.Ready).id)
        assertEquals("Site a", s.title)
        assertNull(TileState.labelRes(s)) // the title is the label
        assertEquals(R.string.tile_codes_tap_to_copy, TileState.subtitleRes(s))
    }

    @Test fun a_locked_vault_shows_the_locked_state_without_a_title() {
        val s = TileState.from(listOf(code("a", null, 0)))
        assertSame(TileState.Locked, s)
        assertFalse(s.active)
        assertEquals(R.string.tile_codes_locked, TileState.labelRes(s))
        assertEquals(R.string.tile_codes_locked_subtitle, TileState.subtitleRes(s))
        assertNull(TileState.codeToCopy(s, listOf(code("a", null, 0))))
    }

    @Test fun on_the_lock_screen_nothing_from_the_vault_shows_or_copies() {
        val codes = listOf(code("a", "123456"))
        val s = TileState.from(codes, deviceLocked = true)
        assertSame(TileState.Locked, s)
        assertNull(TileState.codeToCopy(s, codes))
    }

    @Test fun the_first_pinned_code_that_gives_digits_is_copied_at_the_tap() {
        val codes = listOf(code("a", ""), code("b", "654321"), code("c", "111111"))
        val s = TileState.from(codes)
        assertEquals("b", (s as TileState.Ready).id)
        assertEquals("654321", TileState.codeToCopy(s, codes))
        // The code is the one read at the tap, not one kept from an earlier read.
        assertEquals("999999", TileState.codeToCopy(s, listOf(code("b", "999999"))))
        // The item went (or lost its secret) since: nothing is copied.
        assertNull(TileState.codeToCopy(s, listOf(code("c", "111111"))))
    }

    @Test fun pins_without_a_code_open_the_app() {
        val s = TileState.from(listOf(code("a", ""), code("b", "")))
        assertTrue(s is TileState.NoCode)
        assertFalse(s.active)
        assertEquals("Site a", (s as TileState.NoCode).title)
        assertEquals(R.string.tile_codes_no_code, TileState.subtitleRes(s))
        assertNull(TileState.codeToCopy(s, listOf(code("a", ""))))
    }

    @Test fun a_tap_copies_only_the_pin_whose_title_was_shown() {
        val before = TileState.from(listOf(code("a", "123456"), code("b", "654321")))
        val shown = TileState.shownId(before)
        assertEquals("a", shown)
        // Same first pin at the tap: its live code.
        val same = listOf(code("a", "222222"), code("b", "654321"))
        assertEquals("222222", TileState.codeToCopy(TileState.from(same), same, shown))
        // "a" was unpinned meanwhile: "b" is first now, nothing is copied (the tile refreshes instead).
        val changed = listOf(code("b", "654321"))
        assertNull(TileState.codeToCopy(TileState.from(changed), changed, shown))
        // A tile that showed no title (locked, then the phone unlock): the first pin is copied.
        assertNull(TileState.shownId(TileState.Locked))
        assertEquals("654321", TileState.codeToCopy(TileState.from(changed), changed, null))
    }

    @Test fun one_pin_without_a_read_locks_the_whole_tile() {
        assertSame(TileState.Locked, TileState.from(listOf(code("a", "123456"), code("b", null, 0))))
    }

    @Test fun a_closed_tile_keeps_only_the_tile_name() {
        assertEquals(R.string.tile_codes_name, TileState.CLOSED_LABEL_RES)
    }

    @Test fun to_string_never_shows_a_title() {
        assertFalse(TileState.from(listOf(code("a", "123456"))).toString().contains("Site"))
        assertFalse(TileState.from(listOf(code("a", ""))).toString().contains("Site"))
    }
}
