package app.localgatekeys.android.ui.editor

import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.detail.FakeClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.unlock.TestClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The keyboard each editor field asks for (Swift `test_no_editor_field_uses_a_credential_content_type`, Android side):
 * secrets never learn, suggest or capitalise; plain fields never get a password keyboard.
 */
class EditorKeyboardTest {
    private val passwordTypes = setOf(KeyboardType.Password, KeyboardType.NumberPassword)

    @Test fun single_line_secrets_take_a_password_keyboard_without_autocorrect_or_capitals() {
        for (kind in EditorKind.entries) for (field in kind.fields.filter { it.secret && !it.multiline }) {
            val o = EditorKeyboard.options(field)
            val expected = if (field.keyboard == EditorKind.Keyboard.NUMBER) KeyboardType.NumberPassword else KeyboardType.Password
            assertEquals("$kind.${field.key}", expected, o.keyboardType)
            assertFalse("$kind.${field.key}", o.autoCorrectEnabled ?: true)
            assertEquals("$kind.${field.key}", KeyboardCapitalization.None, o.capitalization)
        }
    }

    @Test fun multi_line_secrets_have_autocorrect_and_capitals_off() {
        val key = EditorKind.SSH_KEY.fields.first { it.key == "private_key" }
        val o = EditorKeyboard.options(key)
        assertFalse(o.autoCorrectEnabled ?: true)
        assertEquals(KeyboardCapitalization.None, o.capitalization)
        assertEquals(KeyboardType.Ascii, o.keyboardType)
    }

    @Test fun plain_fields_never_get_a_password_keyboard() {
        for (kind in EditorKind.entries) for (field in kind.fields.filter { !it.secret }) {
            val o = EditorKeyboard.options(field)
            assertFalse("$kind.${field.key}", o.keyboardType in passwordTypes)
            // Autocorrect only where people write sentences (titles, notes), as on the iPhone.
            assertEquals("$kind.${field.key}", field.caps == EditorKind.Caps.SENTENCES, o.autoCorrectEnabled)
        }
        val origin = EditorKind.WEB.fields.first { it.key == "origin" }
        assertEquals(KeyboardType.Uri, EditorKeyboard.options(origin).keyboardType)
        val name = EditorKind.IDENTITY.fields.first { it.key == "name" }
        assertEquals(KeyboardCapitalization.Words, EditorKeyboard.options(name).capitalization)
        val amount = EditorKind.PURCHASE.fields.first { it.key == "amount_minor" }
        assertEquals(KeyboardType.Decimal, EditorKeyboard.options(amount).keyboardType)
        assertNotEquals(KeyboardType.Password, EditorKeyboard.options(EditorKind.WEB.fields.first { it.key == "username" }).keyboardType)
    }

    @Test fun seams_never_print_their_contents() {
        assertEquals("EditorSeams", EditorSeams(MemoryItemStore()).toString())
        val clock = TestClock(1)
        val clipboard = SecretClipboard(FakeClipboardSink(), AppSettings(MemoryStore()), ManualScheduler(clock), clock)
        assertEquals("DetailSeams(edit=false, delete=false)", DetailSeams(clipboard, CopyToast(true)).toString())
        assertEquals("DetailSeams(edit=true, delete=false)", DetailSeams(clipboard, CopyToast(true), onEdit = {}).toString())
    }
}
