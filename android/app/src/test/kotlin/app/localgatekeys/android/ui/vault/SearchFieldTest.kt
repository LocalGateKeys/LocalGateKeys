package app.localgatekeys.android.ui.vault

import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

/** The vault search field's cursor when the query is set from outside (Ctrl+K, a recent search) or typed. */
class SearchFieldTest {
    /** Release check 2026-11-01: Ctrl+K then "sec" gave "sec> " because the cursor stayed at 0. */
    @Test fun a_query_set_from_outside_puts_the_cursor_at_its_end() {
        val shown = syncedSearchField(TextFieldValue(""), "> ")
        assertEquals("> ", shown.text)
        assertEquals(TextRange(2), shown.selection)
        // Typing at that cursor appends.
        val typed = shown.text.substring(0, shown.selection.start) + "sec" + shown.text.substring(shown.selection.end)
        assertEquals("> sec", typed)
    }

    @Test fun a_recent_search_replacing_typed_text_also_ends_with_the_cursor() {
        val shown = syncedSearchField(TextFieldValue("gar", TextRange(1)), "garage")
        assertEquals(TextRange(6), shown.selection)
    }

    @Test fun while_typing_the_fields_own_cursor_and_selection_are_kept() {
        val typing = TextFieldValue("garage", TextRange(2, 4))
        assertSame(typing, syncedSearchField(typing, "garage"))
    }
}
