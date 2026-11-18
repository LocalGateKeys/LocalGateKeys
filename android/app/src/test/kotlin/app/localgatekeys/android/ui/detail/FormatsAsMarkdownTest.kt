package app.localgatekeys.android.ui.detail

import org.junit.Test
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

class FormatsAsMarkdownTest {
    @Test fun login_notes_and_secure_note_body_are_formatted() {
        assertTrue(formatsAsMarkdown("web", "notes"))
        assertTrue(formatsAsMarkdown("desktop", "notes"))
        assertTrue(formatsAsMarkdown("note", "body"))
        assertTrue(formatsAsMarkdown("note", "notes"))
    }

    @Test fun other_kinds_and_fields_are_not() {
        assertFalse(formatsAsMarkdown("web", "body"))
        assertFalse(formatsAsMarkdown("card", "body"))
        assertFalse(formatsAsMarkdown("note", "title"))
        assertFalse(formatsAsMarkdown("web", "password"))
        assertFalse(formatsAsMarkdown("note", ""))
    }
}
