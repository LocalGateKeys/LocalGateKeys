package app.localgatekeys.android.i18n

import app.localgatekeys.android.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TxtTest {
    private val txt = EnglishTxt()

    @Test
    fun resolves_a_string() {
        assertEquals("Language", txt.s(R.string.settings_language))
        assertEquals("System default", txt.s(R.string.settings_language_system))
    }

    @Test
    fun resolves_a_plural_with_its_argument() {
        assertEquals("1 item", txt.plural(R.plurals.item_count, 1, 1))
        assertEquals("3 items", txt.plural(R.plurals.item_count, 3, 3))
    }

    @Test
    fun picker_has_system_plus_ten_languages() {
        assertEquals(11, LanguageOptions.all.size)
        assertEquals("", LanguageOptions.all.first().tag)
        assertNull(LanguageOptions.all.first().nativeName)
        assertEquals(
            listOf("en", "es", "it", "pl", "zh-Hans", "ja", "de", "pt-BR", "ko", "nl"),
            LanguageOptions.all.drop(1).map { it.tag },
        )
    }

    @Test
    fun current_tag_matches_exactly_then_by_language() {
        assertEquals("", LanguageOptions.currentTag(""))
        assertEquals("pt-BR", LanguageOptions.currentTag("pt-BR"))
        assertEquals("de", LanguageOptions.currentTag("de-AT"))
        assertEquals("", LanguageOptions.currentTag("fr"))
    }
}
