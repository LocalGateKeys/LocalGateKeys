package app.localgatekeys.android.widget

import android.content.Context
import android.content.res.Configuration
import androidx.appcompat.app.AppCompatDelegate

/**
 * [context] with the app's own language (Settings > Language) applied. The widget and the tile render from the
 * application context, which keeps the language the process started with (and, before Android 13, the system's);
 * strings for them are read from this context each time so a language change shows at the next render.
 */
fun appLocaleContext(context: Context): Context {
    val locales = AppCompatDelegate.getApplicationLocales()
    if (locales.isEmpty) return context
    val config = Configuration(context.resources.configuration)
    config.setLocales(android.os.LocaleList.forLanguageTags(locales.toLanguageTags()))
    return context.createConfigurationContext(config)
}
