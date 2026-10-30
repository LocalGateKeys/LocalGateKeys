package app.localgatekeys.android.vault

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.EditorKind
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue

class SearchCommandsTest {
    @Test
    fun plain_queries_are_item_searches() {
        assertNull(SearchCommand.parse("", EnglishTxt()))
        assertNull(SearchCommand.parse("github", EnglishTxt()))
        assertNull(SearchCommand.parse("a>b", EnglishTxt()))
        assertFalse(SearchCommand.isCommandQuery("lock"))
    }

    @Test
    fun bare_prefix_lists_every_available_command_in_order() {
        assertEquals(SearchCommand.all, SearchCommand.parse(">", EnglishTxt()))
        assertEquals(SearchCommand.all, SearchCommand.parse("  >  ", EnglishTxt()))
        val some = listOf(SearchCommand.Lock, SearchCommand.Settings)
        assertEquals(some, SearchCommand.parse(">", EnglishTxt(), some))
    }

    @Test
    fun words_narrow_by_title_and_keywords_case_insensitive() {
        assertEquals(listOf(SearchCommand.Lock), SearchCommand.parse(">LOCK", EnglishTxt()))
        assertEquals(listOf(SearchCommand.GeneratePassword), SearchCommand.parse("> gen pass", EnglishTxt()))
        assertEquals(listOf(SearchCommand.ScanQr), SearchCommand.parse(">qr", EnglishTxt()))
        assertTrue(SearchCommand.parse(">sync", EnglishTxt())!!.containsAll(listOf(SearchCommand.SyncNow, SearchCommand.SyncStatus)))
        assertEquals(listOf(SearchCommand.ExportBackup, SearchCommand.RestoreBackup), SearchCommand.parse(">backup", EnglishTxt()))
        assertEquals(emptyList<SearchCommand>(), SearchCommand.parse(">nothing-like-this", EnglishTxt()))
    }

    @Test
    fun new_item_commands_cover_every_kind() {
        val news = SearchCommand.parse(">new", EnglishTxt())!!.filterIsInstance<SearchCommand.NewItem>().map { it.kind }
        assertEquals(EditorKind.entries, news)
        assertTrue(SearchCommand.parse(">new wifi", EnglishTxt())!!.contains(SearchCommand.NewItem(EditorKind.WIFI)))
    }

    @Test
    fun settings_sections_match_settings() {
        val r = SearchCommand.parse(">settings", EnglishTxt())!!
        assertTrue(r.containsAll(listOf(SearchCommand.Settings, SearchCommand.Import, SearchCommand.ShowSetup)))
    }

    @Test
    fun ctrl_k_is_the_search_shortcut() {
        assertTrue(SearchShortcut.matches(39, 0, ctrl = true, alt = false, shift = false, repeat = 0))
        assertFalse(SearchShortcut.matches(39, 0, ctrl = false, alt = false, shift = false, repeat = 0))
        assertFalse(SearchShortcut.matches(39, 1, ctrl = true, alt = false, shift = false, repeat = 0))
        assertFalse(SearchShortcut.matches(39, 0, ctrl = true, alt = false, shift = false, repeat = 1))
        assertFalse(SearchShortcut.matches(39, 0, ctrl = true, alt = false, shift = true, repeat = 0))
        assertFalse(SearchShortcut.matches(40, 0, ctrl = true, alt = false, shift = false, repeat = 0))
        assertEquals(android.view.KeyEvent.KEYCODE_K, SearchShortcut.KEYCODE_K)
    }
}
