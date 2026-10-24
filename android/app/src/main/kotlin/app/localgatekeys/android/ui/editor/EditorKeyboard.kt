package app.localgatekeys.android.ui.editor

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import app.localgatekeys.android.editor.EditorKind

/**
 * The keyboard each editor field asks for (the Android side of the iPhone's "no credential content type" rule).
 * Secrets never autocorrect or capitalise: a single-line secret takes the password keyboard (no suggestions), a
 * multi-line one (a private key, edited once revealed) a plain ASCII keyboard. Plain fields never get a password
 * keyboard and autocorrect only where people write sentences. Personalised learning is off app-wide
 * (`NoPersonalisedLearning`).
 */
object EditorKeyboard {
    fun options(field: EditorKind.Field): KeyboardOptions = when {
        field.secret && field.multiline ->
            KeyboardOptions(KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii)
        field.secret -> KeyboardOptions(
            KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = if (field.keyboard == EditorKind.Keyboard.NUMBER) KeyboardType.NumberPassword else KeyboardType.Password,
        )
        else -> KeyboardOptions(
            capitalization = when (field.caps) {
                EditorKind.Caps.NONE -> KeyboardCapitalization.None
                EditorKind.Caps.WORDS -> KeyboardCapitalization.Words
                EditorKind.Caps.SENTENCES -> KeyboardCapitalization.Sentences
                EditorKind.Caps.CHARACTERS -> KeyboardCapitalization.Characters
            },
            autoCorrectEnabled = field.caps == EditorKind.Caps.SENTENCES,
            keyboardType = when (field.keyboard) {
                EditorKind.Keyboard.TEXT -> KeyboardType.Text
                EditorKind.Keyboard.URL -> KeyboardType.Uri
                EditorKind.Keyboard.EMAIL -> KeyboardType.Email
                EditorKind.Keyboard.NUMBER -> KeyboardType.Number
                EditorKind.Keyboard.PHONE -> KeyboardType.Phone
                EditorKind.Keyboard.DECIMAL -> KeyboardType.Decimal
            },
        )
    }
}
