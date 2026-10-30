package app.localgatekeys.android.i18n

import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

/** One row of the Language picker: [tag] is a BCP 47 tag ("" for the system language) and [nativeName] its fixed name. */
data class LanguageOption(val tag: String, val nativeName: String?)

/** The ten supported languages in their own names (not translated, the same labels as Windows), after System default. */
object LanguageOptions {
    val all: List<LanguageOption> = listOf(
        LanguageOption("", null),
        LanguageOption("en", "English"),
        LanguageOption("es", "Español"),
        LanguageOption("it", "Italiano"),
        LanguageOption("pl", "Polski"),
        LanguageOption("zh-Hans", "简体中文"),
        LanguageOption("ja", "日本語"),
        LanguageOption("de", "Deutsch"),
        LanguageOption("pt-BR", "Português (Brasil)"),
        LanguageOption("ko", "한국어"),
        LanguageOption("nl", "Nederlands"),
    )

    /** The option for the app's current locale tags ("" when none is set or it is not one of ours). */
    fun currentTag(applied: String): String {
        if (applied.isEmpty()) return ""
        val first = applied.substringBefore(',')
        all.firstOrNull { it.tag.isNotEmpty() && it.tag.equals(first, ignoreCase = true) }?.let { return it.tag }
        val lang = first.substringBefore('-')
        return all.firstOrNull { it.tag.isNotEmpty() && it.tag.substringBefore('-').equals(lang, ignoreCase = true) }?.tag ?: ""
    }

    /** Applies [tag] app-wide; AppCompat stores it (autoStoreLocales) and recreates the activities. */
    fun apply(tag: String) {
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
    }

    fun applied(): String = AppCompatDelegate.getApplicationLocales().toLanguageTags()
}
